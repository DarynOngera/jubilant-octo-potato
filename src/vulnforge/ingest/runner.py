"""Ingestion orchestration."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..paths import Paths
from ..targets.intelligence import IntelligenceSpec
from .osv import IngestError, fetch_osv, load_snapshot, normalize_osv, save_snapshot
from .proposal import load_catalog, merge_advisories, write_proposal

BANDIT_INTELLIGENCE = IntelligenceSpec(
    name="bandit",
    display_name="Bandit",
    ecosystem="Hex",
    package="bandit",
    github_repo="mtrudel/bandit",
    advisories_url="https://hex.pm/packages/bandit/advisories",
)


def ingest_target(
    paths: Paths,
    target: IntelligenceSpec,
    *,
    offline: bool = False,
    apply: bool = False,
    raw_path: Path | None = None,
) -> dict[str, Any]:
    osv_package = target.osv_package
    if osv_package is None:
        raise IngestError(
            f"target {target.name!r} has no OSV package/ecosystem configured"
        )
    cache_path = paths.data / "raw" / "osv" / f"{target.name}.json"
    if offline:
        source_path = raw_path or cache_path
        records = load_snapshot(source_path)
        source = f"cache:{source_path}"
    else:
        response = fetch_osv(osv_package)
        save_snapshot(cache_path, response, package=osv_package)
        records = response.get("vulns", [])
        source = f"osv:{target.name}"

    normalized = normalize_osv(records, package=osv_package)
    if not normalized:
        raise IngestError(
            f"OSV returned no CVE-bearing {target.ecosystem}/{target.package} "
            "advisories; the current data may be synthetic or the upstream "
            "schema changed"
        )

    catalog_path = paths.data / "advisories.json"
    existing = load_catalog(catalog_path)
    merged, changes = merge_advisories(existing, normalized)
    proposed_path, diff_path = write_proposal(paths, merged, existing, changes)

    applied = False
    if apply and (changes["added"] or changes["changed"]):
        catalog_path.write_text(
            json.dumps({"advisories": merged}, indent=2) + "\n"
        )
        applied = True

    return {
        "source": source,
        "target": target.name,
        "normalized": len(normalized),
        "proposed": str(proposed_path),
        "diff": str(diff_path),
        "changes": changes,
        "applied": applied,
    }


def ingest_bandit(
    paths: Paths,
    *,
    offline: bool = False,
    apply: bool = False,
    raw_path: Path | None = None,
) -> dict[str, Any]:
    """Backward-compatible wrapper for the original Bandit-only command."""
    return ingest_target(
        paths,
        BANDIT_INTELLIGENCE,
        offline=offline,
        apply=apply,
        raw_path=raw_path,
    )
