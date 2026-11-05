"""Read-only view models for the local VulnForge UI.

Everything here is derived from artifacts the CLI already writes. The UI never
re-implements validation or detection; it normalizes the JSON and reports what
is present.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import FactoryConfig
from ..doctor import run_doctor
from ..lab import LabOrchestrator
from ..models import Package
from ..packages import find_package, load_packages, validate_package
from ..paths import Paths
from ..targets.loader import load_adapter


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text()
    except FileNotFoundError:
        return None


def _matrix_index(paths: Paths) -> dict[str, dict[str, Any]]:
    rows = _read_json(paths.data / "vulnerability-matrix.json")
    if not isinstance(rows, list):
        return {}
    return {
        str(row.get("cve")): row
        for row in rows
        if isinstance(row, dict) and row.get("cve")
    }


def _package_paths(pkg: Package) -> dict[str, Path]:
    manifest = pkg.manifest
    paths = manifest.paths if manifest else {}
    return {
        "advisory": pkg.root / paths.get("advisory", "advisory.json"),
        "analysis": pkg.root / paths.get("analysis", "analysis"),
        "evidence": pkg.root / paths.get("evidence", "evidence"),
        "detection": pkg.root / paths.get("detection", "detection"),
        "lab": pkg.root / paths.get("lab", "lab/lab.json"),
        "report": pkg.root / paths.get("report", "report.md"),
    }


def _probe_ready(pkg: Package) -> bool:
    if pkg.probe is None:
        return False
    path = pkg.probe.module_path(pkg.root)
    try:
        text = path.read_text()
    except FileNotFoundError:
        return False
    # Scaffolded probes deliberately raise this marker until implemented.
    return "NotImplementedError" not in text


def _lifecycle(
    pkg: Package,
    paths: Paths,
    located: dict[str, Path],
    errors: list[str],
) -> dict[str, Any]:
    manifest = pkg.manifest
    runtime = paths.root / ".vulnforge" / "labs" / pkg.cve / "runtime.json"
    package_ok = manifest is not None and not errors
    lab_ok = runtime.is_file()
    probe_ok = _probe_ready(pkg)
    validation_ok = (located["evidence"] / "validation.json").is_file()
    detection_ok = validation_ok and (located["detection"] / "evidence.json").is_file()
    report_ok = validation_ok and located["report"].is_file()

    stages = {
        "package": {
            "ok": package_ok,
            "label": "package valid" if package_ok else "fix package errors",
        },
        "lab": {
            "ok": lab_ok,
            "label": "lab runtime present" if lab_ok else "start the lab",
        },
        "probe": {
            "ok": probe_ok,
            "label": "probe implemented" if probe_ok else "implement the probe",
        },
        "validation": {
            "ok": validation_ok,
            "label": "validation evidence" if validation_ok else "run validation",
        },
        "detection": {
            "ok": detection_ok,
            "label": "detection evidence" if detection_ok else "run detection",
        },
        "report": {
            "ok": report_ok,
            "label": "report generated" if report_ok else "generate the report",
        },
    }

    readiness: dict[str, dict[str, Any]] = {
        "package_validate": {"enabled": True, "reason": "Package validation is always available."},
        "lab_build": {
            "enabled": package_ok,
            "reason": "Fix package validation errors before building.",
        },
        "lab_start": {
            "enabled": package_ok,
            "reason": "Fix package validation errors before starting the lab.",
        },
        "lab_stop": {
            "enabled": lab_ok,
            "reason": "No lab runtime is recorded for this package.",
        },
        "poc_run": {
            "enabled": lab_ok and probe_ok,
            "reason": "Start the lab and implement the probe first.",
        },
        "validate": {
            "enabled": lab_ok and probe_ok,
            "reason": "Start the lab and implement the probe first.",
        },
        "detect": {
            "enabled": validation_ok,
            "reason": "Run validation before detection.",
        },
        "report": {
            "enabled": validation_ok,
            "reason": "Run validation before generating the report.",
        },
    }

    if not package_ok:
        next_action, next_label = "package_validate", "Fix package errors"
    elif not lab_ok:
        next_action, next_label = "lab_start", "Start lab"
    elif not probe_ok:
        next_action, next_label = None, "Implement the probe"
    elif not validation_ok:
        next_action, next_label = "validate", "Run validation"
    elif not detection_ok:
        next_action, next_label = "detect", "Run detection"
    elif not report_ok:
        next_action, next_label = "report", "Generate report"
    else:
        next_action, next_label = None, "Lifecycle complete"

    return {
        "stages": stages,
        "next_action": next_action,
        "next_label": next_label,
        "actions": readiness,
    }


def _summarize(pkg: Package, paths: Paths, matrix: dict[str, dict[str, Any]]) -> dict[str, Any]:
    manifest = pkg.manifest
    located = _package_paths(pkg)
    validation = _read_json(located["evidence"] / "validation.json") or {}
    detection = _read_json(located["detection"] / "evidence.json") or {}
    provenance = _read_json(located["lab"].parent / "provenance.json") or {}
    errors = validate_package(pkg, paths) if manifest is not None else list(pkg.errors)
    lifecycle = _lifecycle(pkg, paths, located, errors)
    row = matrix.get(pkg.cve, {})
    build = provenance.get("build") or {}
    git = build.get("git") or {}
    targets = validation.get("targets") or {}

    def median(role: str) -> Any:
        return ((targets.get(role) or {}).get("summary") or {}).get("median")

    runs_dir = located["evidence"] / "runs"
    run_files = sorted(runs_dir.glob("*.json")) if runs_dir.is_dir() else []

    return {
        "cve": pkg.cve,
        "title": pkg.advisory.title if pkg.advisory is not None else "",
        "target": manifest.adapter_name if manifest is not None else "",
        "status": manifest.status if manifest is not None else "invalid",
        "verdict": manifest.last_verdict if manifest is not None else "NOT_RUN",
        "detection": detection.get("result") or "NOT_RUN",
        "vulnerable_version": manifest.vulnerable_version if manifest is not None else "",
        "patched_version": manifest.patched_version if manifest is not None else "",
        "priority": row.get("priority_P"),
        "exploit_tier": row.get("exploit_tier"),
        "valid": manifest is not None and not errors,
        "errors": errors,
        "last_run_at": (manifest.validation.get("last_run_at") if manifest else None),
        "validation": {
            "runs": validation.get("runs"),
            "finished_at": validation.get("finished_at"),
            "reason": validation.get("reason"),
            "vulnerable_median": median("vulnerable"),
            "patched_median": median("patched"),
        },
        "detection_reason": detection.get("reason"),
        "git_dirty": git.get("dirty"),
        "git_commit": git.get("commit"),
        "has_report": located["report"].is_file(),
        "run_count": len(run_files),
        "lifecycle": lifecycle,
    }


def _health(pkg: Package, paths: Paths) -> list[dict[str, str]]:
    manifest = pkg.manifest
    located = _package_paths(pkg)
    issues: list[dict[str, str]] = []

    for error in (validate_package(pkg, paths) if manifest is not None else pkg.errors):
        issues.append({"level": "error", "message": error})

    if not (located["evidence"] / "validation.json").is_file():
        issues.append({"level": "warn", "message": "no validation evidence"})
    if not (located["detection"] / "evidence.json").is_file():
        issues.append({"level": "warn", "message": "detection has not been run"})
    if not located["report"].is_file():
        issues.append({"level": "warn", "message": "report has not been generated"})

    provenance = _read_json(located["lab"].parent / "provenance.json") or {}
    git = (provenance.get("build") or {}).get("git") or {}
    if git.get("dirty") is True:
        issues.append(
            {
                "level": "warn",
                "message": "provenance was recorded from a dirty worktree",
            }
        )
    if provenance and not provenance.get("runtime"):
        issues.append(
            {
                "level": "info",
                "message": "provenance has no runtime section (lab not started during build)",
            }
        )
    return issues


def portfolio(cfg: FactoryConfig, paths: Paths) -> dict[str, Any]:
    packages = load_packages(paths)
    matrix = _matrix_index(paths)
    summaries = [_summarize(pkg, paths, matrix) for pkg in packages]
    catalog = _read_json(paths.data / "advisories.json") or {}
    advisories = catalog.get("advisories") if isinstance(catalog, dict) else None

    verdicts: dict[str, int] = {}
    detections: dict[str, int] = {}
    for item in summaries:
        verdicts[item["verdict"]] = verdicts.get(item["verdict"], 0) + 1
        detections[item["detection"]] = detections.get(item["detection"], 0) + 1

    return {
        "packages": summaries,
        "counts": {
            "packages": len(summaries),
            "valid_packages": sum(1 for item in summaries if item["valid"]),
            "confirmed": verdicts.get("CONFIRMED", 0),
            "inconclusive": verdicts.get("INCONCLUSIVE", 0),
            "triggered": detections.get("TRIGGERED", 0),
            "advisories": len(advisories) if isinstance(advisories, list) else 0,
            "needs_action": sum(
                1
                for item in summaries
                if item["lifecycle"]["next_label"] != "Lifecycle complete"
            ),
            "complete": sum(
                1
                for item in summaries
                if item["lifecycle"]["next_label"] == "Lifecycle complete"
            ),
        },
        "verdicts": verdicts,
        "detections": detections,
    }


def package_detail(cfg: FactoryConfig, paths: Paths, cve: str) -> dict[str, Any]:
    pkg = find_package(paths, cve)
    matrix = _matrix_index(paths)
    located = _package_paths(pkg)
    summary = _summarize(pkg, paths, matrix)
    analysis_dir = located["analysis"]
    catalog = _read_json(paths.data / "advisories.json") or {}
    catalog_rows = {
        row.get("cve"): row
        for row in (catalog.get("advisories") or [])
        if isinstance(row, dict)
    }
    return {
        "summary": summary,
        "advisory": _read_json(located["advisory"]),
        "catalog": catalog_rows.get(cve),
        "exploitability": _read_json(analysis_dir / "exploitability.json"),
        "root_cause": _read_text(analysis_dir / "root-cause.md"),
        "attack_surface": _read_text(analysis_dir / "attack-surface.md"),
        "validation": _read_json(located["evidence"] / "validation.json"),
        "detection": _read_json(located["detection"] / "evidence.json"),
        "detection_spec": _read_json(located["detection"] / "spec.json"),
        "provenance": _read_json(located["lab"].parent / "provenance.json"),
        "execution": _read_json(located["evidence"] / "execution.json"),
        "health": _health(pkg, paths),
    }


def matrix(paths: Paths) -> list[dict[str, Any]]:
    rows = _read_json(paths.data / "vulnerability-matrix.json")
    return rows if isinstance(rows, list) else []


def doctor(paths: Paths) -> list[dict[str, Any]]:
    return [
        {"name": check.name, "ok": check.ok, "detail": check.detail}
        for check in run_doctor(paths)
    ]


def docker_ready(paths: Paths) -> bool:
    checks = {check["name"]: check["ok"] for check in doctor(paths)}
    return all(
        checks.get(name, False)
        for name in ("docker", "docker daemon", "docker compose")
    )


def labs(cfg: FactoryConfig, paths: Paths) -> list[dict[str, Any]]:
    packages = load_packages(paths)
    results: list[dict[str, Any]] = []
    for pkg in packages:
        runtime_path = paths.root / ".vulnforge" / "labs" / pkg.cve / "runtime.json"
        provenance_path = pkg.root / "lab" / "provenance.json"
        provenance = _read_json(provenance_path) or {}
        build = provenance.get("build") or {}
        item: dict[str, Any] = {
            "cve": pkg.cve,
            "configured": runtime_path.is_file(),
            "running": False,
            "lab_id": None,
            "created_at": None,
            "services": {},
            "error": None,
            "build": {
                "git": build.get("git") or {},
                "generated_at": provenance.get("generated_at"),
                "base_image": build.get("base_image"),
                "images": provenance.get("images") or {},
            },
        }
        if not runtime_path.is_file():
            results.append(item)
            continue
        manifest = pkg.manifest
        try:
            if manifest is None:
                raise ValueError("package has no manifest")
            adapter = load_adapter(cfg, manifest.adapter_name)
            orchestrator = LabOrchestrator(cfg, paths, adapter)
            status = orchestrator.status(pkg)
            item.update(status)
        except Exception as exc:  # pragma: no cover - environment dependent
            item["error"] = str(exc)
            runtime = _read_json(runtime_path) or {}
            item["lab_id"] = runtime.get("lab_id")
            item["created_at"] = runtime.get("created_at")
            item["services"] = runtime.get("services") or {}
        results.append(item)
    return results


def report_path(paths: Paths, cve: str, kind: str) -> Path:
    pkg = find_package(paths, cve)
    if kind == "json":
        return pkg.root / "report.json"
    return pkg.root / "report.md"
