"""Toy target adapter used to prove the non-Bandit adapter boundary."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ...lab.models import ServicePlan
from ...models import LabTarget
from ...probe.measurement import MeasurementSpec, read_toy_stats
from ..intelligence import IntelligenceSpec

TOY_BASE_IMAGE = "python:3.12-slim"


class ToyAdapter:
    name = "toy"
    base_image = TOY_BASE_IMAGE

    def __init__(self, repo_root: Path, app_dir: Path | None = None):
        self.repo_root = repo_root.resolve()
        self.app_dir = (app_dir or (self.repo_root / "targets" / "toy")).resolve()

    def image_tag(self, cve: str, role: str, version: str) -> str:
        return f"vulnforge/toy:{cve.lower()}-{role}-{version}"

    def build_args(self, version: str, cve: str, role: str) -> dict[str, str]:
        return {"TOY_VERSION": version}

    def lockfile(self, version: str) -> Path | None:
        return None

    def version_from_stats(self, stats: dict[str, Any]) -> str | None:
        value = stats.get("toy_version")
        return str(value) if value is not None else None

    def labels(
        self, cve: str, role: str, version: str, git_commit: str
    ) -> dict[str, str]:
        return {
            "org.opencontainers.image.title": "vulnforge/toy",
            "org.opencontainers.image.revision": git_commit,
            "org.opencontainers.image.version": version,
            "com.vulnforge.cve": cve,
            "com.vulnforge.target": self.name,
            "com.vulnforge.role": role,
            "com.vulnforge.toy.version": version,
        }

    def service(
        self,
        target: LabTarget,
        service: ServicePlan,
        limits: dict[str, Any],
    ) -> dict[str, Any]:
        mem_limit = int(limits["mem_limit_mb"])
        return {
            "image": service.image_tag,
            "build": {
                "context": str(self.app_dir),
                "args": dict(service.build_args),
                "labels": dict(service.labels),
            },
            "container_name": service.container_name,
            # The toy target uses one listener for both app and stats.
            "ports": [f"127.0.0.1:{service.app_port}:4000"],
            "environment": {"TOY_VERSION": service.version},
            "labels": dict(service.labels),
            "mem_limit": f"{mem_limit}m",
            "mem_reservation": f"{max(1, mem_limit // 4)}m",
            "cpus": str(limits["cpus"]),
            "pids_limit": int(limits["pids_limit"]),
            "read_only": True,
            "tmpfs": ["/tmp"],
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "restart": "no",
            "logging": {
                "driver": "json-file",
                "options": {"max-size": "10m", "max-file": "3"},
            },
        }

    def health(self, target: LabTarget) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(
                f"{target.base_url.rstrip('/')}/healthz", timeout=3
            ) as response:
                body = response.read().decode().strip()
                return response.status == 200 and body == "ok", body
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            return False, str(exc)

    def stats(self, target: LabTarget) -> dict[str, Any] | None:
        try:
            with urllib.request.urlopen(
                f"{target.base_url.rstrip('/')}/stats", timeout=3
            ) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, ConnectionError, TimeoutError, json.JSONDecodeError):
            return None

    def measurement(self) -> MeasurementSpec:
        # The toy target is a single-listener Python process. It has no
        # forced-GC endpoint, but it does expose native memory counters.
        return MeasurementSpec(
            gc_path=None,
            reader=read_toy_stats,
            use_app_listener=True,
        )

    def intelligence(self) -> IntelligenceSpec:
        # The toy target has no public advisory feed or commit host.
        return IntelligenceSpec(name=self.name, display_name="Toy")
