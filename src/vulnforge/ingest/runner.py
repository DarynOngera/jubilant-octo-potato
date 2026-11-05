"""Ingestion orchestration."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..paths import Paths
from .osv import IngestError, fetch_osv, load_snapshot, normalize_osv, save_snapshot
from .proposal import load_catalog, merge_advisories, write_proposal


def ingest_bandit(
    paths: Paths,
    *,
    offline: bool = False,
    apply: bool = False,
    raw_path: Path | None = None,
) -> dict[str, Any]:
    cache_path = paths.root / "data" / "raw" / "osv" / "bandit.json"
    if offline:
        source_path = raw_path or cache_path
        records = load_snapshot(source_path)
        source = f"cache:{source_path}"
    else:
        response = fetch_osv()
        save_snapshot(cache_path, response)
        records = response.get("vulns", [])
        source = "osv"

    normalized = normalize_osv(records)
    if not normalized:
        raise IngestError(
            "OSV returned no CVE-bearing Hex/bandit advisories; "
            "the current data may be synthetic or the upstream schema changed"
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
        "normalized": len(normalized),
        "proposed": str(proposed_path),
        "diff": str(diff_path),
        "changes": changes,
        "applied": applied,
    }
