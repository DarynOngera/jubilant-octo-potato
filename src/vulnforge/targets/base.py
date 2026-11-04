"""Target adapter contract."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from ..lab.models import ServicePlan
from ..models import LabTarget


class TargetAdapter(Protocol):
    """Target-specific image/lab/health behavior.

    The factory core must not import a concrete adapter. Adapters are resolved
    from ``config/vulnforge.yaml`` at runtime.
    """

    name: str
    base_image: str
    app_dir: Path

    def image_tag(self, cve: str, role: str, version: str) -> str: ...

    def build_args(self, version: str, cve: str, role: str) -> dict[str, str]: ...

    def labels(
        self, cve: str, role: str, version: str, git_commit: str
    ) -> dict[str, str]: ...

    def service(
        self,
        target: LabTarget,
        service: ServicePlan,
        limits: dict[str, Any],
    ) -> dict[str, Any]: ...

    def health(self, target: LabTarget) -> tuple[bool, str]: ...

    def stats(self, target: LabTarget) -> dict[str, Any] | None: ...
