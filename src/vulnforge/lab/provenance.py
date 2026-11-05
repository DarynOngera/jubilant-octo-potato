"""Image and build provenance recording."""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import FactoryConfig
from ..errors import LabError
from ..models import Package
from ..targets.base import TargetAdapter
from . import docker
from .models import LabPlan, LabRuntime


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_state(root: Path) -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        return {"commit": commit, "dirty": bool(status.strip())}
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        return {"commit": None, "dirty": None, "error": str(exc)}


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())


def _lockfiles(adapter: TargetAdapter, plan: LabPlan) -> dict[str, dict[str, str]]:
    locks: dict[str, dict[str, str]] = {}
    versions = sorted({service.version for service in plan.services.values()})
    for version in versions:
        path = adapter.lockfile(version)
        if path is None:
            continue
        if not path.is_file():
            raise LabError(
                f"missing lockfile for {version}: {path}. "
                "Add the adapter's lockfile for that version."
            )
        locks[version] = {"path": _relative(path, adapter.repo_root), "sha256": sha256_file(path)}
    return locks


def _image_record(tag: str) -> dict[str, Any]:
    data = docker.image_inspect(tag)
    config = data.get("Config") or {}
    return {
        "tag": tag,
        "id": data.get("Id"),
        "repo_digests": list(data.get("RepoDigests") or []),
        "created": data.get("Created"),
        "architecture": data.get("Architecture"),
        "os": data.get("Os"),
        "size": data.get("Size"),
        "labels": dict(config.get("Labels") or {}),
    }


def build_provenance(
    cfg: FactoryConfig,
    adapter: TargetAdapter,
    package: Package,
    plan: LabPlan,
    runtime: LabRuntime | None = None,
) -> dict[str, Any]:
    if package.manifest is None:
        raise LabError(f"package {package.cve} has no manifest")

    dockerfile = adapter.app_dir / "Dockerfile"
    if not dockerfile.is_file():
        raise LabError(f"missing Dockerfile: {dockerfile}")

    images = {
        role: _image_record(service.image_tag)
        for role, service in plan.services.items()
    }

    data: dict[str, Any] = {
        "schema_version": "1.0",
        "cve": package.cve,
        "target": package.manifest.adapter_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "build": {
            "app_dir": _relative(adapter.app_dir, cfg.root),
            "dockerfile": {
                "path": _relative(dockerfile, cfg.root),
                "sha256": sha256_file(dockerfile),
            },
            "base_image": adapter.base_image,
            "lockfiles": _lockfiles(adapter, plan),
            "build_args": {
                role: service.build_args for role, service in plan.services.items()
            },
            "git": git_state(cfg.root),
        },
        "images": images,
    }

    if runtime is not None:
        data["runtime"] = {
            "lab_id": runtime.lab_id,
            "network": runtime.network,
            "compose_path": str(runtime.compose_path),
            "created_at": runtime.created_at,
            "services": {
                role: {
                    "name": service.name,
                    "version": service.version,
                    "container_name": service.container_name,
                    "base_url": service.base_url,
                    "admin_url": service.admin_url,
                    "app_port": service.app_port,
                    "admin_port": service.admin_port,
                }
                for role, service in runtime.services.items()
            },
        }
    return data


def write_provenance(package: Package, data: dict[str, Any]) -> Path:
    path = package.root / "lab" / "provenance.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path
