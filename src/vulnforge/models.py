"""Lightweight data models for VulnForge packages.

The JSON Schemas in ``schemas/`` are the external contract. These dataclasses
are a convenience layer for the CLI and cross-file checks; they deliberately
keep unknown nested structures as plain dicts so the factory can evolve
without a code change for every advisory field.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Advisory:
    cve: str
    title: str
    affected: Any
    fixed_in: Any
    track: str
    references: list[str]
    schema_version: str = "1.0"
    ghsa: str | None = None
    osv: str | None = None
    published: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_ranges: list[Any] = field(default_factory=list)
    commits: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Advisory":
        return cls(
            schema_version=str(data.get("schema_version", "1.0")),
            cve=str(data["cve"]),
            title=str(data["title"]),
            affected=data["affected"],
            fixed_in=data["fixed_in"],
            track=str(data["track"]),
            references=list(data.get("references", [])),
            ghsa=data.get("ghsa"),
            osv=data.get("osv"),
            published=data.get("published"),
            cvss_score=data.get("cvss_score"),
            cvss_vector=data.get("cvss_vector"),
            affected_ranges=list(data.get("affected_ranges", [])),
            commits=list(data.get("commits", [])),
            provenance=dict(data.get("provenance", {})),
        )


@dataclass(frozen=True)
class PackageManifest:
    cve: str
    target: str
    status: str
    versions: dict[str, Any]
    paths: dict[str, str]
    validation: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PackageManifest":
        return cls(
            schema_version=str(data.get("schema_version", "1.0")),
            cve=str(data["cve"]),
            target=str(data["target"]),
            status=str(data["status"]),
            versions=dict(data["versions"]),
            paths=dict(data["paths"]),
            validation=dict(data.get("validation", {})),
            provenance=dict(data.get("provenance", {})),
        )

    @property
    def vulnerable_version(self) -> str:
        return str(self.versions.get("vulnerable", ""))

    @property
    def patched_version(self) -> str:
        return str(self.versions.get("patched", ""))

    @property
    def first_fixed(self) -> str:
        return str(self.versions.get("first_fixed", ""))

    @property
    def last_verdict(self) -> str:
        return str(self.validation.get("last_verdict", "NOT_RUN"))


@dataclass(frozen=True)
class LabTarget:
    role: str
    name: str
    version: str
    base_url: str
    admin_url: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LabTarget":
        return cls(
            role=str(data["role"]),
            name=str(data["name"]),
            version=str(data["version"]),
            base_url=str(data["base_url"]),
            admin_url=str(data["admin_url"]),
        )


@dataclass(frozen=True)
class LabSpec:
    cve: str
    target: str
    app: str
    versions: dict[str, str]
    targets: list[LabTarget]
    limits: dict[str, Any]
    network: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LabSpec":
        return cls(
            schema_version=str(data.get("schema_version", "1.0")),
            cve=str(data["cve"]),
            target=str(data["target"]),
            app=str(data["app"]),
            network=data.get("network"),
            versions={str(k): str(v) for k, v in dict(data["versions"]).items()},
            targets=[LabTarget.from_dict(t) for t in data["targets"]],
            limits=dict(data["limits"]),
            provenance=dict(data.get("provenance", {})),
        )

    def target_by_role(self, role: str) -> LabTarget | None:
        for target in self.targets:
            if target.role == role:
                return target
        return None


@dataclass(frozen=True)
class ProbeManifest:
    cve: str
    entrypoint: str
    targets: dict[str, str]
    kwargs: dict[str, Any]
    metric: str
    thresholds: dict[str, Any]
    runs: int = 1
    disruptive: bool = False
    schema_version: str = "1.0"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProbeManifest":
        return cls(
            schema_version=str(data.get("schema_version", "1.0")),
            cve=str(data["cve"]),
            entrypoint=str(data["entrypoint"]),
            targets={str(k): str(v) for k, v in dict(data["targets"]).items()},
            kwargs=dict(data.get("kwargs", {})),
            metric=str(data["metric"]),
            thresholds=dict(data["thresholds"]),
            runs=int(data.get("runs", 1)),
            disruptive=bool(data.get("disruptive", False)),
        )

    def module_path(self, package_root: Path) -> Path:
        module, _, _func = self.entrypoint.partition(":")
        return package_root / (module.replace(".", "/") + ".py")


@dataclass
class Package:
    root: Path
    manifest: PackageManifest | None = None
    advisory: Advisory | None = None
    lab: LabSpec | None = None
    probe: ProbeManifest | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def cve(self) -> str:
        if self.manifest is not None:
            return self.manifest.cve
        return self.root.name

    @property
    def is_valid(self) -> bool:
        return not self.errors and self.manifest is not None
