"""Repository/workspace path discovery."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigError


def find_repo_root(start: Path | None = None) -> Path:
    """Return the VulnForge workspace root.

    ``VULNFORGE_ROOT`` wins when set. Otherwise walk up from ``start`` (or the
    current directory) looking for the factory's ``pyproject.toml`` and
    ``config`` directory.
    """
    env = os.environ.get("VULNFORGE_ROOT")
    if env:
        root = Path(env).expanduser().resolve()
        if not (root / "pyproject.toml").exists():
            raise ConfigError(
                f"VULNFORGE_ROOT={root} does not contain pyproject.toml"
            )
        return root

    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").exists() and (candidate / "config").is_dir():
            return candidate
    raise ConfigError(
        "Could not locate the VulnForge root (no pyproject.toml + config/ "
        "found). Set VULNFORGE_ROOT or run from the repository."
    )


@dataclass(frozen=True)
class Paths:
    root: Path
    packages: Path
    data: Path
    evidence: Path
    reports: Path
    config: Path
    schemas: Path

    @classmethod
    def from_root(
        cls,
        root: Path,
        *,
        packages_dir: str = "vulnerabilities",
        data_dir: str = "data",
        evidence_dir: str = "evidence",
        reports_dir: str = "reports",
        schemas_dir: str = "schemas",
    ) -> "Paths":
        root = root.resolve()
        return cls(
            root=root,
            packages=root / packages_dir,
            data=root / data_dir,
            evidence=root / evidence_dir,
            reports=root / reports_dir,
            config=root / "config",
            schemas=root / schemas_dir,
        )
