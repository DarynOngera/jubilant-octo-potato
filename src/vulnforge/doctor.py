"""Environment diagnostics for the factory."""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .paths import Paths


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _run(args: list[str], timeout: int = 15) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (result.stdout or result.stderr or "").strip().splitlines()
    detail = output[0] if output else f"exit {result.returncode}"
    return result.returncode == 0, detail


def run_doctor(paths: Paths) -> list[Check]:
    checks: list[Check] = []
    checks.append(
        Check(
            "python",
            sys.version_info >= (3, 10),
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
    )
    checks.append(
        Check(
            "config/vulnforge.yaml",
            (paths.config / "vulnforge.yaml").is_file(),
            str(paths.config / "vulnforge.yaml"),
        )
    )
    checks.append(
        Check(
            "schemas",
            paths.schemas.is_dir() and any(paths.schemas.glob("*.schema.json")),
            str(paths.schemas),
        )
    )
    package_count = len(list(paths.packages.glob("CVE-*"))) if paths.packages.is_dir() else 0
    checks.append(
        Check("packages", paths.packages.is_dir(), f"{package_count} package(s) in {paths.packages}")
    )
    checks.append(
        Check(
            "lab limits",
            (paths.config / "lab-limits.yaml").is_file(),
            str(paths.config / "lab-limits.yaml"),
        )
    )
    checks.append(
        Check(
            "report generator",
            (paths.root / "reports" / "generate_report.py").is_file(),
            str(paths.root / "reports" / "generate_report.py"),
        )
    )
    docker_ok, docker_detail = _run(["docker", "--version"])
    checks.append(Check("docker", docker_ok, docker_detail))
    info_ok, info_detail = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
    checks.append(Check("docker daemon", info_ok, info_detail))
    compose_ok, compose_detail = _run(["docker", "compose", "version", "--short"])
    checks.append(Check("docker compose", compose_ok, compose_detail))
    return checks


def clean_runtime(paths: Paths, dry_run: bool = False) -> list[Path]:
    base = paths.root / ".vulnforge"
    if not base.exists():
        return []
    removed: list[Path] = []
    for path in sorted(base.rglob("*"), reverse=True):
        if path.is_file():
            removed.append(path)
            if not dry_run:
                path.unlink(missing_ok=True)
        elif path.is_dir() and not any(path.iterdir()):
            removed.append(path)
            if not dry_run:
                path.rmdir()
    if not dry_run and base.exists() and not any(base.iterdir()):
        removed.append(base)
        base.rmdir()
    elif dry_run and base.exists() and not any(base.iterdir()):
        removed.append(base)
    return removed
