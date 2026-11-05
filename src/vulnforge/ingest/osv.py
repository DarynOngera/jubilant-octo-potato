"""OSV API ingestion and normalization."""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..errors import VulnForgeError

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
DEFAULT_OSV_PACKAGE = {"name": "bandit", "ecosystem": "Hex"}
OSV_PACKAGE = DEFAULT_OSV_PACKAGE


class IngestError(VulnForgeError):
    pass


def fetch_osv(
    package: dict[str, str] | None = None, timeout: int = 30
) -> dict[str, Any]:
    payload = json.dumps({"package": package or DEFAULT_OSV_PACKAGE}).encode()
    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise IngestError(f"OSV query failed: {exc}") from exc


def save_snapshot(
    path: Path,
    response: dict[str, Any],
    source: str = OSV_QUERY_URL,
    package: dict[str, str] | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(response, sort_keys=True).encode()
    snapshot = {
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "package": package or DEFAULT_OSV_PACKAGE,
        "response_sha256": hashlib.sha256(canonical).hexdigest(),
        "response": response,
    }
    path.write_text(json.dumps(snapshot, indent=2) + "\n")
    return path


def load_snapshot(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise IngestError(f"OSV snapshot not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"invalid OSV snapshot {path}: {exc}") from exc
    response = data.get("response", data)
    vulns = response.get("vulns", [])
    if not isinstance(vulns, list):
        raise IngestError(f"OSV snapshot has no vulns list: {path}")
    return [vuln for vuln in vulns if isinstance(vuln, dict)]


def _first_alias(record: dict[str, Any], prefix: str) -> str | None:
    for alias in record.get("aliases", []):
        if isinstance(alias, str) and alias.startswith(prefix):
            return alias
    identifier = record.get("id")
    if isinstance(identifier, str) and identifier.startswith(prefix):
        return identifier
    return None


def _range_string(event_range: dict[str, Any]) -> str | None:
    introduced = None
    fixed = None
    for event in event_range.get("events", []):
        if "introduced" in event:
            introduced = event["introduced"]
        if "fixed" in event:
            fixed = event["fixed"]
    if introduced and fixed:
        return f">= {introduced} and < {fixed}"
    if introduced:
        return f">= {introduced}"
    if fixed:
        return f"< {fixed}"
    return None


def normalize_osv_record(
    record: dict[str, Any], package: dict[str, str] | None = None
) -> dict[str, Any] | None:
    cve = _first_alias(record, "CVE-")
    if cve is None:
        return None
    ghsa = _first_alias(record, "GHSA-")
    expected = package or DEFAULT_OSV_PACKAGE
    ranges: list[str] = []
    fixed_versions: list[str] = []
    for affected in record.get("affected", []):
        if not isinstance(affected, dict):
            continue
        affected_package = affected.get("package", {})
        if (
            affected_package.get("ecosystem") != expected.get("ecosystem")
            or affected_package.get("name") != expected.get("name")
        ):
            continue
        for event_range in affected.get("ranges", []):
            if not isinstance(event_range, dict):
                continue
            text = _range_string(event_range)
            if text:
                ranges.append(text)
            for event in event_range.get("events", []):
                if isinstance(event, dict) and event.get("fixed"):
                    fixed_versions.append(str(event["fixed"]))

    fixed_versions = sorted(set(fixed_versions))
    fixed_in: str | list[str] | None
    if len(fixed_versions) == 1:
        fixed_in = fixed_versions[0]
    elif fixed_versions:
        fixed_in = fixed_versions
    else:
        fixed_in = None

    references = [
        ref.get("url")
        for ref in record.get("references", [])
        if isinstance(ref, dict) and ref.get("url")
    ]
    commits = [
        ref["url"].rstrip("/").split("/")[-1]
        for ref in record.get("references", [])
        if isinstance(ref, dict)
        and isinstance(ref.get("url"), str)
        and "/commit/" in ref["url"]
    ]
    severity = record.get("severity") or []
    cvss_vector = None
    for entry in severity:
        if isinstance(entry, dict) and entry.get("type") in ("CVSS_V4", "CVSS_V3"):
            cvss_vector = entry.get("score")
            break

    affected = " or ".join(ranges) if ranges else None
    published = record.get("published")
    return {
        "cve": cve,
        "ghsa": ghsa,
        "osv": record.get("id"),
        "title": record.get("summary") or record.get("details", "")[:120] or cve,
        "published": published[:10] if isinstance(published, str) else None,
        "cvss_score": None,
        "cvss_vector": cvss_vector,
        "affected": affected,
        "affected_ranges": ranges or None,
        "fixed_in": fixed_in,
        "track": "unclassified",
        "commits": sorted(set(commits)),
        "references": sorted(set(references)),
        "provenance": {
            "source": "osv",
            "source_url": OSV_QUERY_URL,
            "notes": "Normalized from an OSV API response; human review required.",
        },
    }


def normalize_osv(
    records: list[dict[str, Any]], package: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    normalized = []
    for record in records:
        item = normalize_osv_record(record, package=package)
        if item is not None:
            normalized.append(item)
    return sorted(normalized, key=lambda item: item["cve"])
