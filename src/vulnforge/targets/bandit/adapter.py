"""Bandit target adapter."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ...lab.models import ServicePlan
from ...models import LabTarget
from ...probe.measurement import MeasurementSpec
from ..intelligence import IntelligenceSpec

BANDIT_BASE_IMAGE = (
    "hexpm/elixir:1.17.3-erlang-27.1.2-debian-bookworm-20241202-slim"
    "@sha256:318497672d700b95c95a3195549e30c8451ab7e6eb5f462415653b94ab1032b6"
)
SOURCE_URL = "https://github.com/DarynOngera/jubilant-octo-potato"


class BanditAdapter:
    name = "bandit"
    base_image = BANDIT_BASE_IMAGE

    def __init__(self, repo_root: Path, app_dir: Path | None = None):
        self.repo_root = repo_root.resolve()
        self.app_dir = (app_dir or (self.repo_root / "lab" / "app")).resolve()

    def image_tag(self, cve: str, role: str, version: str) -> str:
        return f"vulnforge/bandit:{cve.lower()}-{role}-{version}"

    def build_args(self, version: str, cve: str, role: str) -> dict[str, str]:
        return {"BANDIT_VERSION": version}

    def lockfile(self, version: str) -> Path | None:
        return self.app_dir / "locks" / f"mix-{version}.lock"

    def version_from_stats(self, stats: dict[str, Any]) -> str | None:
        value = stats.get("bandit_version")
        return str(value) if value is not None else None

    def labels(
        self, cve: str, role: str, version: str, git_commit: str
    ) -> dict[str, str]:
        return {
            "org.opencontainers.image.title": "vulnforge/bandit",
            "org.opencontainers.image.source": SOURCE_URL,
            "org.opencontainers.image.revision": git_commit,
            "org.opencontainers.image.version": version,
            "com.vulnforge.cve": cve,
            "com.vulnforge.target": self.name,
            "com.vulnforge.role": role,
            "com.vulnforge.bandit.version": version,
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
            "ports": [
                f"127.0.0.1:{service.app_port}:4000",
                f"127.0.0.1:{service.admin_port}:4001",
            ],
            "environment": {
                "MAX_BODY_LENGTH": "1000000",
                "READ_TIMEOUT_MS": "15000",
                "BANDIT_HTTP2": "true",
                "APP_PORT": "4000",
                "ADMIN_PORT": "4001",
                "ERL_AFLAGS": "+Q 262144",
            },
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
        url = f"{target.base_url.rstrip('/')}/healthz"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                body = response.read().decode("utf-8", "replace").strip()
                if response.status == 200 and body == "ok":
                    return True, body
                return False, f"HTTP {response.status}: {body[:120]}"
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            return False, str(exc)

    def stats(self, target: LabTarget) -> dict[str, Any] | None:
        url = f"{target.admin_url.rstrip('/')}/stats"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, ConnectionError, TimeoutError, json.JSONDecodeError):
            return None

    def measurement(self) -> MeasurementSpec:
        # The Bandit lab app exposes BEAM memory, process, and /gc endpoints.
        return MeasurementSpec()

    def intelligence(self) -> IntelligenceSpec:
        return IntelligenceSpec(
            name=self.name,
            display_name="Bandit",
            ecosystem="Hex",
            package="bandit",
            github_repo="mtrudel/bandit",
            advisories_url="https://hex.pm/packages/bandit/advisories",
        )
