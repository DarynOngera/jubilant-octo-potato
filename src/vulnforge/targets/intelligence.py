"""Target-provided intelligence metadata.

Ingestion and source analysis need a package/ecosystem identifier and a commit
host.  Keeping those values on the adapter prevents ``ingest`` from hardcoding
one target's OSV/GitHub coordinates.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IntelligenceSpec:
    name: str
    display_name: str
    ecosystem: str | None = None
    package: str | None = None
    github_repo: str | None = None
    advisories_url: str | None = None

    @property
    def osv_package(self) -> dict[str, str] | None:
        if not self.package or not self.ecosystem:
            return None
        return {"name": self.package, "ecosystem": self.ecosystem}
