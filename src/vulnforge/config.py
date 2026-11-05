"""Factory configuration loading."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError
from .paths import Paths, find_repo_root


@dataclass(frozen=True)
class TargetConfig:
    name: str
    adapter: str | None = None
    app_dir: str | None = None
    limits: str | None = None


@dataclass(frozen=True)
class FactoryConfig:
    root: Path
    packages_dir: str = "vulnerabilities"
    data_dir: str = "data"
    evidence_dir: str = "evidence"
    reports_dir: str = "reports"
    schemas_dir: str = "schemas"
    default_runs: int = 3
    max_cv: float = 0.25
    require_distinct_targets: bool = True
    targets: dict[str, TargetConfig] = field(default_factory=dict)

    def paths(self) -> Paths:
        return Paths.from_root(
            self.root,
            packages_dir=self.packages_dir,
            data_dir=self.data_dir,
            evidence_dir=self.evidence_dir,
            reports_dir=self.reports_dir,
            schemas_dir=self.schemas_dir,
        )

    def target(self, name: str) -> TargetConfig:
        try:
            return self.targets[name]
        except KeyError as exc:
            raise ConfigError(
                f"Target {name!r} is not configured. Known targets: "
                f"{', '.join(sorted(self.targets)) or '<none>'}"
            ) from exc


def _as_dict(value: Any, field_name: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{field_name} must be a mapping")
    return value


def _as_int(value: Any, field_name: str, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigError(f"{field_name} must be a positive integer")
    return value


def _as_number(value: Any, field_name: str, default: float) -> float:
    if value is None:
        return default
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        raise ConfigError(f"{field_name} must be a non-negative number")
    return float(value)


def load_config(root: Path | None = None) -> FactoryConfig:
    root = (root or find_repo_root()).resolve()
    config_path = root / "config" / "vulnforge.yaml"
    raw: dict[str, Any] = {}
    if config_path.exists():
        try:
            loaded = yaml.safe_load(config_path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML in {config_path}: {exc}") from exc
        raw = _as_dict(loaded, str(config_path))

    factory = _as_dict(raw.get("factory"), "factory")
    validation = _as_dict(raw.get("validation"), "validation")
    target_rows = _as_dict(raw.get("targets"), "targets")

    targets: dict[str, TargetConfig] = {}
    for name, row in target_rows.items():
        row = _as_dict(row, f"targets.{name}")
        targets[name] = TargetConfig(
            name=name,
            adapter=row.get("adapter"),
            app_dir=row.get("app_dir"),
            limits=row.get("limits"),
        )

    return FactoryConfig(
        root=root,
        packages_dir=str(factory.get("packages_dir", "vulnerabilities")),
        data_dir=str(factory.get("data_dir", "data")),
        evidence_dir=str(factory.get("evidence_dir", "evidence")),
        reports_dir=str(factory.get("reports_dir", "reports")),
        schemas_dir=str(factory.get("schemas_dir", "schemas")),
        default_runs=_as_int(validation.get("default_runs"), "validation.default_runs", 3),
        max_cv=_as_number(validation.get("max_cv"), "validation.max_cv", 0.25),
        require_distinct_targets=bool(
            validation.get("require_distinct_targets", True)
        ),
        targets=targets,
    )
