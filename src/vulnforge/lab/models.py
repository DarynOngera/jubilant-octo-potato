"""Lab plan/runtime data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ServicePlan:
    role: str
    name: str
    version: str
    image_tag: str
    container_name: str
    build_args: dict[str, str]
    labels: dict[str, str]
    base_url: str
    admin_url: str
    app_port: int
    admin_port: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "name": self.name,
            "version": self.version,
            "image": self.image_tag,
            "container_name": self.container_name,
            "build_args": self.build_args,
            "labels": self.labels,
            "base_url": self.base_url,
            "admin_url": self.admin_url,
            "app_port": self.app_port,
            "admin_port": self.admin_port,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServicePlan":
        return cls(
            role=str(data["role"]),
            name=str(data["name"]),
            version=str(data["version"]),
            image_tag=str(data.get("image", data.get("image_tag", ""))),
            container_name=str(data["container_name"]),
            build_args=dict(data.get("build_args", {})),
            labels=dict(data.get("labels", {})),
            base_url=str(data["base_url"]),
            admin_url=str(data["admin_url"]),
            app_port=int(data.get("app_port", 0)),
            admin_port=int(data.get("admin_port", 0)),
        )


@dataclass(frozen=True)
class LabPlan:
    cve: str
    target: str
    lab_id: str
    network: str
    compose_path: Path
    runtime_path: Path
    services: dict[str, ServicePlan]

    def service(self, role: str) -> ServicePlan:
        try:
            return self.services[role]
        except KeyError as exc:
            raise KeyError(f"lab plan has no {role!r} service") from exc


@dataclass(frozen=True)
class LabRuntime:
    cve: str
    target: str
    lab_id: str
    network: str
    compose_path: Path
    runtime_path: Path
    services: dict[str, ServicePlan]
    created_at: str
    extra: dict[str, Any] = field(default_factory=dict)

    def service(self, role: str) -> ServicePlan:
        try:
            return self.services[role]
        except KeyError as exc:
            raise KeyError(f"lab runtime has no {role!r} service") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "cve": self.cve,
            "target": self.target,
            "lab_id": self.lab_id,
            "network": self.network,
            "compose_path": str(self.compose_path),
            "created_at": self.created_at,
            "services": {role: svc.to_dict() for role, svc in self.services.items()},
            **self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LabRuntime":
        return cls(
            cve=str(data["cve"]),
            target=str(data["target"]),
            lab_id=str(data["lab_id"]),
            network=str(data["network"]),
            compose_path=Path(data["compose_path"]),
            runtime_path=Path(data["runtime_path"]) if data.get("runtime_path") else Path(),
            services={
                role: ServicePlan.from_dict(svc)
                for role, svc in dict(data["services"]).items()
            },
            created_at=str(data["created_at"]),
            extra={
                key: value
                for key, value in data.items()
                if key
                not in {
                    "schema_version",
                    "cve",
                    "target",
                    "lab_id",
                    "network",
                    "compose_path",
                    "runtime_path",
                    "created_at",
                    "services",
                }
            },
        )
