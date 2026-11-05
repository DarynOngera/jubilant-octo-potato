"""Target adapter contract."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from ..lab.models import ServicePlan
    from ..models import LabTarget
    from ..probe.measurement import MeasurementSpec
    from .intelligence import IntelligenceSpec


class TargetAdapter(Protocol):
    """Target-specific image/lab/health/measurement behavior.

    The factory core must not import a concrete adapter. Adapters are resolved
    from ``config/vulnforge.yaml`` at runtime.
    """

    name: str
    base_image: str
    app_dir: Path
    repo_root: Path

    def __init__(self, repo_root: Path, app_dir: Path | None = None) -> None: ...

    def image_tag(self, cve: str, role: str, version: str) -> str: ...

    def build_args(self, version: str, cve: str, role: str) -> dict[str, str]: ...

    def labels(
        self, cve: str, role: str, version: str, git_commit: str
    ) -> dict[str, str]: ...

    def lockfile(self, version: str) -> Path | None:
        """Return the dependency lockfile for a version, or None if not applicable."""
        ...

    def version_from_stats(self, stats: dict[str, Any]) -> str | None:
        """Extract the reported target version from a stats payload."""
        ...

    def service(
        self,
        target: LabTarget,
        service: ServicePlan,
        limits: dict[str, Any],
    ) -> dict[str, Any]: ...

    def health(self, target: LabTarget) -> tuple[bool, str]: ...

    def stats(self, target: LabTarget) -> dict[str, Any] | None: ...

    def measurement(self) -> MeasurementSpec:
        """Return stats/GC paths and the reader that normalizes stats."""
        ...

    def intelligence(self) -> IntelligenceSpec:
        """Return the target's OSV/GitHub intelligence coordinates."""
        ...
