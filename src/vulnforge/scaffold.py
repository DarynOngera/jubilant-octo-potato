"""Create a valid draft package from the global advisory catalog."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import FactoryConfig
from .errors import PackageError
from .lab.ports import allocate_ports
from .paths import Paths


def _load_version_resolver(paths: Paths):
    path = paths.root / "triage" / "version_resolver.py"
    if not path.is_file():
        raise PackageError(f"version resolver not found: {path}")
    spec = importlib.util.spec_from_file_location("vulnforge_version_resolver", path)
    if spec is None or spec.loader is None:
        raise PackageError(f"could not load version resolver: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return module


def _catalog_row(paths: Paths, cve: str) -> dict[str, Any]:
    catalog_path = paths.data / "advisories.json"
    try:
        rows = json.loads(catalog_path.read_text())["advisories"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as exc:
        raise PackageError(f"could not read advisory catalog {catalog_path}: {exc}") from exc
    for row in rows:
        if isinstance(row, dict) and row.get("cve") == cve:
            return row
    raise PackageError(f"{cve} is not present in {catalog_path}")


def _version_pair(paths: Paths, advisory: dict[str, Any]) -> tuple[str, str]:
    resolver = _load_version_resolver(paths)
    try:
        checkpoints = resolver.suggested_checkpoints([advisory])
    except (KeyError, ValueError) as exc:
        raise PackageError(
            f"could not derive a version pair for {advisory.get('cve')}: {exc}"
        ) from exc
    vulnerable = [row for row in checkpoints if "last-vulnerable" in row["roles"]]
    patched = [row for row in checkpoints if "first-patched" in row["roles"]]
    if len(vulnerable) != 1 or len(patched) != 1:
        raise PackageError(
            f"{advisory['cve']} does not have one unambiguous last-vulnerable/"
            "first-patched checkpoint; pass --vulnerable/--patched explicitly"
        )
    return str(vulnerable[0]["version"]), str(patched[0]["version"])


def _validate_pair(paths: Paths, advisory: dict[str, Any], vulnerable: str, patched: str) -> None:
    resolver = _load_version_resolver(paths)
    if not resolver.version_in_range(vulnerable, advisory):
        raise PackageError(
            f"{vulnerable} is not in {advisory['cve']}'s affected range "
            f"{advisory.get('affected')!r}"
        )
    fixed = advisory.get("fixed_in")
    fixed_values = fixed if isinstance(fixed, list) else [fixed]
    if patched not in {str(value) for value in fixed_values}:
        raise PackageError(
            f"{patched} is not a fixed release for {advisory['cve']}; "
            f"expected one of {fixed!r}"
        )


def _lab_limits(paths: Paths) -> dict[str, Any]:
    raw = yaml.safe_load((paths.config / "lab-limits.yaml").read_text()) or {}
    resource = raw.get("resource_ceilings", {})
    bounds = raw.get("experiment_bounds", {})
    return {
        "mem_limit_mb": int(resource.get("mem_limit_mb", 512)),
        "cpus": float(resource.get("cpu_limit_cores", 1.0)),
        "pids_limit": int(resource.get("pids_limit", 512)),
        "max_duration_seconds": int(bounds.get("max_duration_seconds", 120)),
        "max_request_bytes_total": int(
            bounds.get("max_request_bytes_total", 268435456)
        ),
    }


def _write(path: Path, content: str, force: bool, created: list[Path]) -> None:
    if path.exists() and not force:
        raise PackageError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    created.append(path)


def _json_write(path: Path, data: Any, force: bool, created: list[Path]) -> None:
    _write(path, json.dumps(data, indent=2) + "\n", force, created)


def _advisory(row: dict[str, Any], paths: Paths) -> dict[str, Any]:
    keep = {
        "cve",
        "ghsa",
        "osv",
        "title",
        "published",
        "cvss_score",
        "cvss_vector",
        "affected",
        "affected_ranges",
        "fixed_in",
        "track",
        "commits",
        "references",
    }
    data = {key: value for key, value in row.items() if key in keep}
    data["schema_version"] = "1.0"
    data["provenance"] = {
        "source": "data/advisories.json",
        "source_url": f"file://{paths.data / 'advisories.json'}",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "notes": "Scaffolded; replace this with the source snapshot/hash when available.",
    }
    return data


def _exploitability(paths: Paths, cve: str, advisory: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {}
    matrix_path = paths.data / "vulnerability-matrix.json"
    if matrix_path.is_file():
        try:
            rows = json.loads(matrix_path.read_text())
        except json.JSONDecodeError:
            rows = []
        if isinstance(rows, list):
            row = next((item for item in rows if item.get("cve") == cve), {})
    return {
        "schema_version": "1.0",
        "cve": cve,
        "impact_I": int(row.get("impact_I", 0)),
        "exploit_E": int(row.get("exploit_E", 0)),
        "reach_R": int(row.get("reach_R", 0)),
        "detect_D": int(row.get("detect_D", 0)),
        "priority_P": float(row.get("priority_P", 0.0)),
        "exploit_tier": str(row.get("exploit_tier", "unclassified")),
        "prerequisites": ["TODO: list the prerequisites"],
        "impact": str(row.get("title") or advisory["title"]),
        "notes": str(row.get("notes", "TODO: explain the exploitability assessment.")),
        "source": {"scaffold": "data/vulnerability-matrix.json"},
    }


def _lab(
    cfg: FactoryConfig,
    paths: Paths,
    cve: str,
    target: str,
    vulnerable: str,
    patched: str,
    ports: list[int],
) -> tuple[dict[str, Any], dict[str, Any]]:
    versions = {"vulnerable": vulnerable, "patched": patched}
    names = {"vulnerable": "vulnerable", "patched": "patched"}
    target_config = cfg.target(target)
    app = target_config.app_dir or "lab/app"
    limits = _lab_limits(paths)
    targets = []
    for index, role in enumerate(("vulnerable", "patched")):
        targets.append(
            {
                "role": role,
                "name": names[role],
                "version": versions[role],
                "base_url": f"http://127.0.0.1:{ports[index * 2]}",
                "admin_url": f"http://127.0.0.1:{ports[index * 2 + 1]}",
            }
        )
    lab = {
        "schema_version": "1.0",
        "cve": cve,
        "adapter": target,
        "app": app,
        "network": f"vulnforge-{cve.lower()}",
        "versions": versions,
        "targets": targets,
        "limits": limits,
        "provenance": {
            "source": "config/lab-limits.yaml",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": "Scaffolded; the supported lab path renders Compose dynamically.",
        },
    }
    return lab, versions


def scaffold_package(
    cfg: FactoryConfig,
    paths: Paths,
    cve: str,
    *,
    target: str = "bandit",
    vulnerable: str | None = None,
    patched: str | None = None,
    force: bool = False,
) -> list[Path]:
    """Create a valid draft package for ``cve`` and return created paths."""
    row = _catalog_row(paths, cve)
    if (vulnerable is None) != (patched is None):
        raise PackageError("pass both --vulnerable and --patched, or neither")
    if vulnerable is None or patched is None:
        vulnerable, patched = _version_pair(paths, row)
    _validate_pair(paths, row, vulnerable, patched)

    package_root = paths.packages / cve
    if package_root.exists() and not force:
        raise PackageError(
            f"package directory already exists: {package_root}; use --force to overwrite files"
        )

    created: list[Path] = []
    ports = allocate_ports(4)
    advisory = _advisory(row, paths)
    _json_write(package_root / "advisory.json", advisory, force, created)

    package = {
        "schema_version": "1.0",
        "cve": cve,
        "adapter": target,
        "status": "draft",
        "versions": {
            "vulnerable": vulnerable,
            "patched": patched,
            "first_fixed": patched,
            "affected": row.get("affected_ranges") or [row.get("affected")],
        },
        "paths": {
            "advisory": "advisory.json",
            "analysis": "analysis",
            "lab": "lab/lab.json",
            "poc": "poc/manifest.json",
            "tests": "tests",
            "detection": "detection",
            "evidence": "evidence",
            "report": "report.md",
        },
        "validation": {
            "predicate": "TODO: replace with the exact predicate in poc/manifest.json",
        },
        "provenance": {
            "source": "data/advisories.json",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": "Scaffolded draft; fill in the probe, predicate, and analysis.",
        },
    }
    _json_write(package_root / "package.json", package, force, created)

    lab, _versions = _lab(cfg, paths, cve, target, vulnerable, patched, ports)
    _json_write(package_root / "lab" / "lab.json", lab, force, created)

    probe_manifest = {
        "schema_version": "1.0",
        "cve": cve,
        "entrypoint": "poc.exploit:run",
        "targets": {"vulnerable": "vulnerable", "patched": "patched"},
        "kwargs": {},
        "metric": "attack_memory_delta",
        "thresholds": {
            "vulnerable_min": 0,
            "patched_max": 0,
            "min_samples": 3,
            "max_cv": 0.35,
            "mode": "absolute",
        },
        "runs": 3,
        "disruptive": False,
    }
    _json_write(package_root / "poc" / "manifest.json", probe_manifest, force, created)
    _write(
        package_root / "poc" / "exploit.py",
        '''"""Package probe template.

Implement ``run`` for this CVE, then replace the placeholder metric and
thresholds in ``poc/manifest.json``.
"""
from __future__ import annotations

from vulnforge.probe import ProbeResult, ProbeTarget


def run(target: ProbeTarget, **kwargs) -> ProbeResult:
    raise NotImplementedError("implement the package probe for this CVE")
''',
        force,
        created,
    )
    _write(
        package_root / "poc" / "README.md",
        f"# {cve} PoC\n\nReplace this scaffold with the probe description.\n",
        force,
        created,
    )

    _write(
        package_root / "analysis" / "root-cause.md",
        f"# {cve} — Root cause\n\n**Status:** draft. Replace this scaffold with the "
        "reviewed mechanism and fix.\n",
        force,
        created,
    )
    _write(
        package_root / "analysis" / "attack-surface.md",
        f"# {cve} — Attack surface\n\nTODO: describe the reachable endpoint and "
        "preconditions.\n",
        force,
        created,
    )
    _json_write(
        package_root / "analysis" / "exploitability.json",
        _exploitability(paths, cve, advisory),
        force,
        created,
    )

    _write(
        package_root / "detection" / "spec.json",
        json.dumps(
            {
                "schema_version": "1.0",
                "cve": cve,
                "signal": "TODO: describe the observable for this CVE",
                "evidence_source": "probe observations + lab telemetry",
                "rules": [
                    {
                        "id": "memory_per_connection_outlier",
                        "source": "probe observations",
                        "description": "TODO: choose a rule and justify the threshold.",
                        "threshold": {"stdevs": 3.0},
                        "expected": {"vulnerable": "unknown", "patched": "unknown"},
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        force,
        created,
    )
    _write(
        package_root / "detection" / "README.md",
        f"# {cve} detection\n\n`spec.json` maps the generic rules to this CVE. "
        "Replace the scaffolded rule before validation.\n",
        force,
        created,
    )
    _write(
        package_root / "tests" / "README.md",
        "# Package-local tests\n\nAdd probe contract and A/B reproduction tests here.\n",
        force,
        created,
    )
    _write(
        package_root / "report.md",
        f"# {cve} — Technical Report\n\n> Scaffolded draft. Run "
        f"`vulnforge report {cve}` after validation.\n",
        force,
        created,
    )
    return created
