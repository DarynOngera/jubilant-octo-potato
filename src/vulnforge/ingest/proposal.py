"""Merge ingested advisories into the catalog and produce a reviewable diff."""
from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any

from ..errors import VulnForgeError

PRESERVE_IF_MISSING = (
    "cvss_score",
    "cvss_vector",
    "affected",
    "fixed_in",
    "ghsa",
    "osv",
    "published",
    "track",
)


def load_catalog(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise VulnForgeError(f"advisory catalog not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise VulnForgeError(f"invalid advisory catalog {path}: {exc}") from exc
    advisories = data.get("advisories", [])
    if not isinstance(advisories, list):
        raise VulnForgeError(f"advisory catalog has no advisories list: {path}")
    return [row for row in advisories if isinstance(row, dict)]


def merge_advisories(
    existing: list[dict[str, Any]],
    ingested: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    by_cve = {str(row.get("cve")): dict(row) for row in existing if row.get("cve")}
    added: list[str] = []
    changed: list[dict[str, Any]] = []
    unchanged: list[str] = []

    for incoming in ingested:
        cve = str(incoming.get("cve"))
        if cve not in by_cve:
            by_cve[cve] = dict(incoming)
            added.append(cve)
            continue

        current = by_cve[cve]
        updated = dict(current)
        fields: list[str] = []
        for field in PRESERVE_IF_MISSING:
            value = incoming.get(field)
            if value is None:
                continue
            if field == "track" and value == "unclassified" and current.get("track"):
                continue
            if current.get(field) != value:
                updated[field] = value
                fields.append(field)

        for field in ("commits", "references"):
            merged = sorted(
                set(current.get(field) or []) | set(incoming.get(field) or [])
            )
            if merged != (current.get(field) or []):
                updated[field] = merged
                fields.append(field)

        if incoming.get("provenance"):
            provenance = dict(current.get("provenance") or {})
            provenance.update(incoming["provenance"])
            updated["provenance"] = provenance
            if fields:
                fields.append("provenance")

        if updated.get("affected_ranges") is None and current.get("affected_ranges"):
            updated["affected_ranges"] = current["affected_ranges"]
        if incoming.get("affected_ranges") is not None:
            updated["affected_ranges"] = incoming["affected_ranges"]

        by_cve[cve] = updated
        if fields:
            changed.append({"cve": cve, "fields": sorted(set(fields))})
        else:
            unchanged.append(cve)

    merged = sorted(by_cve.values(), key=lambda row: str(row.get("cve")))
    changes = {
        "added": sorted(added),
        "changed": sorted(changed, key=lambda item: item["cve"]),
        "unchanged": sorted(unchanged),
    }
    return merged, changes


def diff_text(
    existing: list[dict[str, Any]],
    merged: list[dict[str, Any]],
) -> str:
    before = json.dumps(
        {"advisories": sorted(existing, key=lambda row: str(row.get("cve")))},
        indent=2,
        sort_keys=True,
    ).splitlines()
    after = json.dumps(
        {"advisories": merged}, indent=2, sort_keys=True
    ).splitlines()
    return "\n".join(
        difflib.unified_diff(
            before,
            after,
            fromfile="data/advisories.json",
            tofile="data/proposed/advisories.json",
            lineterm="",
        )
    )


def write_proposal(
    paths,
    merged: list[dict[str, Any]],
    existing: list[dict[str, Any]],
    changes: dict[str, Any],
) -> tuple[Path, Path]:
    proposed_dir = paths.root / "data" / "proposed"
    proposed_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = proposed_dir / "advisories.json"
    diff_path = proposed_dir / "diff.txt"
    catalog_path.write_text(
        json.dumps({"advisories": merged}, indent=2) + "\n"
    )
    diff_path.write_text(diff_text(existing, merged) + "\n")
    return catalog_path, diff_path
